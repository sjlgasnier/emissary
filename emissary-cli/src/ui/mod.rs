// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use emissary_core::events::EventSubscriber;
use iced::{
    time,
    widget::{button, column, container, row, toggler, Column, Text},
    Alignment, Element, Length, Subscription, Task, Theme,
};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
enum View {
    Overview,
    Destinations,
    Settings,
}

#[derive(Debug, Clone)]
enum Message {
    ButtonPressed(View),
    ThemeToggled(bool),
    CopyToClipboard(String),
    Tick,
}

pub struct RouterUi {
    events: EventSubscriber,
    bandwith: usize,
    transit_bandwidth: usize,
    num_transit_tunnels: usize,
    num_routers: usize,
    uptime: Instant,
    view: View,
    light_mode: bool,
    server_destinations: Vec<(String, String)>,
    client_destinations: Vec<String>,
}

impl RouterUi {
    fn new(events: EventSubscriber) -> (Self, Task<Message>) {
        (
            RouterUi {
                bandwith: 0usize,
                num_routers: 0usize,
                num_transit_tunnels: 0usize,
                light_mode: true,
                events,
                transit_bandwidth: 0usize,
                uptime: Instant::now(),
                view: View::Overview,
                server_destinations: Vec::new(),
                client_destinations: Vec::new(),
            },
            Task::none(),
        )
    }

    pub fn start(events: EventSubscriber) -> anyhow::Result<()> {
        iced::application("emissary", RouterUi::update, RouterUi::view)
            .subscription(RouterUi::subscription)
            .theme(RouterUi::theme)
            .run_with(|| RouterUi::new(events))
            .map_err(From::from)
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Tick => {
                while let Some(status) = self.events.router_status() {
                    self.transit_bandwidth = status.transit.bandwidth;
                    self.num_transit_tunnels = status.transit.num_tunnels;
                    self.bandwith = status.transport.bandwidth;
                    self.num_routers = status.transport.num_connected_routers;
                    self.server_destinations.extend(status.server_destinations);
                    self.client_destinations.extend(status.client_destinations);
                }

                Task::none()
            }
            Message::ButtonPressed(view) => {
                self.view = view;

                Task::none()
            }
            Message::ThemeToggled(value) => {
                self.light_mode = value;

                Task::none()
            }
            Message::CopyToClipboard(address) => iced::clipboard::write(address),
        }
    }

    fn view(&self) -> Element<Message> {
        let sidebar = column![
            button("Overview").on_press(Message::ButtonPressed(View::Overview)),
            button("Destinations").on_press(Message::ButtonPressed(View::Destinations)),
            button("Settings").on_press(Message::ButtonPressed(View::Settings)),
        ]
        .spacing(10)
        .padding(10)
        .align_x(Alignment::Start);

        let main_content = match self.view {
            View::Overview => {
                let mut uptime = self.uptime.elapsed().as_secs();
                if uptime == 0 {
                    uptime = 1;
                }

                let uptime_text = Text::new(format!(
                    "Uptime {} h {} min {} s",
                    uptime / 60 / 60,
                    uptime / 60,
                    uptime % 60,
                ));
                let total_bandwidth_text = Text::new(format!(
                    "Total bandwidth: {} KB ({} KB/s)",
                    self.bandwith,
                    (self.bandwith / uptime as usize) / 1000
                ));
                let num_connected_text =
                    Text::new(format!("Number of connected routers: {}", self.num_routers));
                let num_transit_tunnels_text =
                    Text::new(format!("Transit tunnels: {}", self.num_transit_tunnels));
                let transit_bandwidth_text = Text::new(format!(
                    "Transit bandwidth: {} KB ({} KB/s)",
                    self.transit_bandwidth,
                    (self.transit_bandwidth / uptime as usize) / 1000
                ));

                column![
                    Text::new("Overview").size(36),
                    uptime_text,
                    total_bandwidth_text,
                    num_connected_text,
                    num_transit_tunnels_text,
                    transit_bandwidth_text,
                ]
                .spacing(20)
                .padding(30)
                .align_x(Alignment::Start)
            }
            View::Destinations => {
                let mut test = Vec::new();

                test.push(Text::new("Server destinations").size(36).into());

                for (name, address) in &self.server_destinations {
                    test.push(
                        row![
                            Text::new(format!("{name}: {address}")),
                            button("Copy to clipboard")
                                .on_press(Message::CopyToClipboard(address.to_string()))
                        ]
                        .spacing(10)
                        .into(),
                    );
                }

                test.push(Text::new("Client destinations").size(36).into());

                for name in &self.client_destinations {
                    test.push(Text::new(format!("{name}")).into());
                }

                Column::from_vec(test).spacing(20).padding(30).align_x(Alignment::Start)
            }
            View::Settings => column![
                Text::new("Settings").size(36),
                toggler(self.light_mode)
                    .label("Light mode")
                    .on_toggle(Message::ThemeToggled)
                    .spacing(10)
            ]
            .spacing(20)
            .padding(30)
            .align_x(Alignment::Start),
        };

        let content_container = container(main_content).padding(20).width(Length::FillPortion(3));

        let layout = row![sidebar, content_container]
            .height(Length::Fill)
            .width(Length::Fill)
            .spacing(10);

        container(layout).height(Length::Fill).width(Length::Fill).into()
    }

    fn subscription(&self) -> Subscription<Message> {
        time::every(Duration::from_millis(500)).map(|_| Message::Tick)
    }

    fn theme(&self) -> Theme {
        if self.light_mode {
            Theme::Light
        } else {
            Theme::Dark
        }
    }
}
